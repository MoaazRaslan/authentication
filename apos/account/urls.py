from django.urls import path
from account import views
urlpatterns = [
    path('users/',views.listUsers,name='list-users'),
    path('user/',views.editProfile,name='edit-profile'),
]
