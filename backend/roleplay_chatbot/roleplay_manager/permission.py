from rest_framework import permissions
from rest_framework import serializers
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken


class IsValidUser(permissions.BasePermission):
    """
    Allows access only to authenticated users.
    """
    message = ('Access token has been expired.')

    def has_permission(self, request, view):
        _ = self.message
        if request.META.get('HTTP_USER_REFRESH_TOKEN', None):
            outstanding = OutstandingToken.objects.filter(token=request.META['HTTP_USER_REFRESH_TOKEN']).last()
            if outstanding:
                if BlacklistedToken.objects.filter(token_id=outstanding.id).exists():
                    raise serializers.ValidationError(code=400)
            return bool(request.user and request.user.is_authenticated)
        raise serializers.ValidationError(detail='You dont have permission to perform this action.', code=400)
