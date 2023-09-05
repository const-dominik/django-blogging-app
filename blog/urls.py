from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView
from blog import views

urlpatterns = [
    path('<uuid:token>/', views.activate_account, name="activate"),
    path('reset_password/<uuid:token>', views.reset_password, name='token_reset_password'),
    path('reset_password/', views.user_reset_password, name="reset_password"),
    path('change_password/', views.change_password, name="change_password"),
    path('register/', views.register, name="register"),
    path('login/', views.user_login, name="login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('posts/<int:entry_id>', views.entry_detail, name="entry_detail"),
    path('profile/<str:nickname>', views.user_profile, name="profile"),
    path('profile/follow/<str:nickname>/<int:unfollow>/', views.follow, name="follow"),
    path('profile/', views.edit_profile, name="edit_profile"),
    path('add_entry/', views.add_entry, name="add_entry"),
    path('posts/remove_entry/<int:entry_id>', views.remove_entry, name="remove_entry"),
    path('posts/edit_entry/<int:entry_id>', views.edit_entry, name="edit_entry"),
    path('posts/load_more', views.load_more_entries, name="load"),
    path('', views.indexView, name="index")
]
if settings.DEBUG is True:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)