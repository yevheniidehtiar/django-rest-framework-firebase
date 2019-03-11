import firebase_admin
from firebase_admin import credentials
from rest_framework_firebase.settings import api_settings
from django.utils.encoding import smart_text
from rest_framework import exceptions
from firebase_admin import auth
from django.utils.translation import ugettext as _
from django.contrib.auth import get_user_model

import logging
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)

if api_settings.FIREBASE_ACCOUNT_KEY_FILE:
    creds = credentials.Certificate(api_settings.FIREBASE_ACCOUNT_KEY_FILE)
else:
    creds = credentials.Certificate(api_settings.FIREBASE_CREDENTIALS)

firebase = firebase_admin.initialize_app(creds, name=api_settings.FIREBASE_APP_NAME)

logger = logging.Logger('Firebase Auth REST')


class BaseFirebaseAuthentication(BaseAuthentication):
    """
    Token based authentication using firebase.
    """
    user_cls = get_user_model()
    uid_field = api_settings.FIREBASE_UID_FIELD
    user = None

    def get_token(self, request):
        raise NotImplementedError

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using Firebase authentication.  Otherwise returns `None`.
        """
        firebase_token = self.get_token(request)
        if firebase_token is None:
            return None

        try:
            payload = auth.verify_id_token(firebase_token, app=firebase)
        except ValueError:
            msg = _('Signature has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except auth.AuthError:
            msg = _('Could not log in.')
            raise exceptions.AuthenticationFailed(msg)

        user = self.authenticate_credentials(payload) or None

        return (user, payload)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and phone_number or email.
        """
        uid = payload['uid']
        if not uid:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)
        try:
            # if use email
            if not api_settings.FIREBASE_PHONE_AUTH and payload.get('email_verified', False) is False:
                msg = _('User email not yet confirmed.')
                raise exceptions.AuthenticationFailed(msg)
            user = self.user_cls.objects.get(**{self.uid_field: uid})
        except self.user_cls.DoesNotExist:
            if not api_settings.FIREBASE_CREATE_NEW_USER:
                msg = _('Invalid signature.')
                raise exceptions.AuthenticationFailed(msg)

            # Make a new user here!
            self.user = auth.get_user(uid, app=firebase)
            user = self.create_user()

        if user is not None and not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)
        return user or None

    def get_email(self):
        if self.user.email:
            return self.user.email
        if self.user.phone_number:
            return str(self.user.phone_number).replace('+', '') + api_settings.FIREBASE_USER_MAIL_SUFFIX
        return api_settings.FIREBASE_USER_MAIL_DEFAULT

    def get_username(self):
        if self.user:
            if self.user.display_name:
                return self.user.display_name
            else:
                return self.get_email()

    def get_defaults(self):
        return {
            self.uid_field: self.user.uid,
            'username': self.get_username(),
            'email': self.get_email(),
            'phone_number': self.user.phone_number
        }

    @property
    def query(self):
        if api_settings.FIREBASE_PHONE_AUTH:
            return {'phone_number': self.user.phone_number}
        return {'email': self.user.email}

    @property
    def defaults(self):
        fields = self.get_defaults()
        if api_settings.FIREBASE_PHONE_AUTH:
            fields.pop('phone_number')  # prevent duplicate kwargs
        else:
            fields.pop('email')  # prevent duplicate kwargs
        return fields

    def create_user(self):
        """
        Try to create or get django user instance
        :return object or None:
        """
        try:
            user, created = self.user_cls.objects.get_or_create(defaults=self.defaults, **self.query)
            if created:
                return user
            # if found user by `query` try to save firebase uid to db
            elif user is not None:
                setattr(user, self.uid_field, self.user.uid)
                user.save()
                return user
        except Exception as e:
            logger.error(e)
            msg = _('Error on user account creating. Please, write to support')
            raise exceptions.AuthenticationFailed(msg)
        return None


class FirebaseAuthentication(BaseFirebaseAuthentication):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    """
    www_authenticate_realm = 'api'

    def get_token(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.FIREBASE_AUTH_HEADER_PREFIX.lower()

        if not auth:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        return auth[1]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        auth_header_prefix = api_settings.FIREBASE_AUTH_HEADER_PREFIX.lower()
        return '{0} realm="{1}"'.format(auth_header_prefix, self.www_authenticate_realm)
