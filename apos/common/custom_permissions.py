from rest_framework import permissions

class IsManager(permissions.BasePermission):

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.is_valid == True
            and request.user.role.name == 'manager'
        )
    
class IsAdmin(permissions.BasePermission):

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.is_valid == True
            and request.user.role.name == 'Admin'
        )