from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
import uuid, os

# Create your models here.
class UserWithAuthToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    reset_token = models.CharField(max_length=300, default='', editable=False) #this one isn't uuid as token is hashed in db
    reset_token_created_at = models.DateTimeField(default=timezone.now)
    activated = models.BooleanField(default=False)

class Profile(models.Model):
    user_with_token = models.OneToOneField(
        UserWithAuthToken,
        on_delete=models.CASCADE,
    )
    avatar = models.ImageField(
        upload_to='photos/user_avatars',
        default='photos/default/user.png',
    )
    about_me = models.CharField(max_length=240, default="")
    followers = models.ManyToManyField(User, related_name="followers")
    following = models.ManyToManyField(User, related_name="following")

    def __str__(self):
        return self.user_with_token.user.get_username()
    
class BlogEntry(models.Model):
    author = models.ForeignKey(Profile, on_delete=models.CASCADE)
    title = models.CharField(max_length=70)
    content = models.CharField(max_length=15000) #average word is 5.1 char in english and appearently blog post should have like 2k words
    thumbnail = models.ImageField(
        upload_to='photos/entry_thumbnails',
        default='photos/default/blogentry.jpg'
    )
    created_at = models.DateTimeField(default=timezone.now)