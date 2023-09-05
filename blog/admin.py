from django.contrib import admin
from .models import UserWithAuthToken, Profile, BlogEntry

# Register your models here.
class UserWithAuthTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'reset_token', 'reset_token_created_at', 'activated')

class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user_with_token', 'about_me', 'avatar')

class BlogEntryAdmin(admin.ModelAdmin):
    list_display = ('author', 'title', 'content', 'thumbnail', 'created_at')

admin.site.register(UserWithAuthToken, UserWithAuthTokenAdmin)
admin.site.register(Profile, ProfileAdmin)
admin.site.register(BlogEntry, BlogEntryAdmin)