from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import User, Profile, BlogEntry

class RegistrationForm(UserCreationForm):
    name = forms.CharField(label="", max_length=20, required=True, widget=forms.TextInput(attrs={'placeholder': 'Name'}))
    surname = forms.CharField(label="", max_length=40, required=True, widget=forms.TextInput(attrs={'placeholder': 'Surname'}))
    email = forms.EmailField(label="", max_length=254, required=True, widget=forms.TextInput(attrs={'placeholder': 'Email'}))
    username = forms.CharField(label="", max_length=20, required=True, widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    password1 = forms.CharField(label="", widget=forms.PasswordInput(attrs={'placeholder': 'Password'}), required=True)
    password2 = forms.CharField(label="", widget=forms.PasswordInput(attrs={'placeholder': 'Confrim password'}), required=True)

    class Meta:
        model = User
        fields = ['name', 'surname', 'email', 'username', 'password1', 'password2']

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Username", max_length=20, required=True)
    password = forms.CharField(label="Password", widget=forms.PasswordInput, required=True)

class ResetPasswordForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=254, required=True)

class NewPasswordForm(forms.Form):
    password = forms.CharField(label="Password", widget=forms.PasswordInput, required=True)

class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(label="Old password", widget=forms.PasswordInput, required=True)
    new_password = forms.CharField(label="New password", widget=forms.PasswordInput, required=True)

class ProfileEditForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['avatar', 'about_me']

    avatar = forms.ImageField(required=False)
    about_me = forms.CharField(required=False, widget=forms.Textarea(attrs={'rows': 3}))

    def clean(self):
        cleaned_data = super().clean()
        avatar = cleaned_data.get('avatar')
        about_me = cleaned_data.get('about_me')

        if not avatar and not about_me:
            raise forms.ValidationError("You are not changing anything.")
        
        return cleaned_data
    
class AddEntryForm(forms.ModelForm):
    title = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Entry title', 'class': 'title'}), label='')
    content = forms.CharField(widget=forms.Textarea(attrs={'placeholder': 'Content'}), label='')
    class Meta:
        model = BlogEntry
        fields = ['title', 'content', 'thumbnail']

class EntryEditForm(forms.ModelForm):
    title = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Entry title'}), label='')
    content = forms.CharField(widget=forms.Textarea(attrs={'placeholder': 'Content'}), label='')
    
    class Meta:
        model = BlogEntry
        fields = ['title', 'content', 'thumbnail']

    def __init__(self, *args, **kwargs):
        super(EntryEditForm, self).__init__(*args, **kwargs)
        self.fields['title'].required = False
        self.fields['content'].required = False
        self.fields['thumbnail'].required = False

    def clean(self):
        cleaned_data = super().clean()
        title = cleaned_data.get('title')
        about_me = cleaned_data.get('content')
        thumbnail = cleaned_data.get('thumbnail')

        if not title and not about_me and not thumbnail:
            raise forms.ValidationError("You are not changing anything")
        
        return cleaned_data
    
class PostFilterForm(forms.Form):
    FILTER_CHOICES = (
        ('recent', 'Recent Posts'),
        ('followed', 'Posts from Followed users'),
    )
    
    filter_type = forms.ChoiceField(choices=FILTER_CHOICES, required=False, label='')