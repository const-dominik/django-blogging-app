from django.shortcuts import render, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError, PermissionDenied
from django.core.validators import validate_email
from django.core.mail import send_mail
from django.http import HttpResponse, HttpRequest, HttpResponseRedirect, JsonResponse
from django.db.models import Q
from django.utils import timezone
from django.urls import reverse
from datetime import timedelta
from .models import UserWithAuthToken, Profile, BlogEntry
from .forms import RegistrationForm, LoginForm, ResetPasswordForm, NewPasswordForm, ProfileEditForm, AddEntryForm, ChangePasswordForm, EntryEditForm, PostFilterForm
import uuid, bcrypt, json

reset_tokens = {}

def make_error_message(errors):
    all_errors = []
    for err_list in errors.values():
        for err in err_list:
            for mess in err.messages:
                all_errors.append(mess)
    return "\n".join(all_errors)

def send_verificaton_email(email, subject, message):
    send_mail(
        subject,
        message,
        "test@gmail.com",
        [email],
        fail_silently=False
    )

def serialize_entry(entry: BlogEntry):
    author = entry.author.user_with_token.user
    serialized = {
        'author': {
            'name': author.first_name,
            'surname': author.last_name,
            'username': author.username,
            'avatar': entry.author.avatar.url
        },
        'title': entry.title,
        'content': entry.content,
        'thumbnail': entry.thumbnail.url,
        'created_at': entry.created_at,
        'id': entry.id
    }
    return serialized

def load_more_entries(request):
    data = json.loads(request.body.decode('utf-8'))
    last_loaded = data.get('lastLoaded')
    followed_or_recent = data.get('followedOrRecent')
    new_entries = []
    if followed_or_recent == "recent":
        new_entries = BlogEntry.objects.order_by('-created_at')[last_loaded:last_loaded+2]
    else:
        following = request.user.userwithauthtoken.profile.following.all()
        entries = BlogEntry.objects.filter(author__user_with_token__user__in=following)
        new_entries = entries[last_loaded:last_loaded+2]
    serialized_data = [serialize_entry(entry) for entry in new_entries]
    return JsonResponse(data=serialized_data, safe=False)


#INDEX
def indexView(request):
    form = PostFilterForm(request.GET)
    
    last_entries = BlogEntry.objects.order_by('-created_at')[:2]
    if form.is_valid() and request.user.id:
        filter_type = form.cleaned_data.get('filter_type')
        following = request.user.userwithauthtoken.profile.following.all()
        if filter_type == 'followed':
            entries = BlogEntry.objects.filter(author__user_with_token__user__in=following)
            last_entries = entries[:2]
    
    return render(request, 'blog/index.html', { 'user': request.user, 'last_entries': last_entries, 'form': form })


# AUTH STUFF
def register(request):
    context = {
        'form': RegistrationForm(),
        'error': '',
        'success': '',
        'user': request.user
    }
    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        if form.is_valid():
            name = form.cleaned_data['name']
            surname = form.cleaned_data['surname']
            email = form.cleaned_data['email']
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']

            try:
                user = User.objects.get(Q(email=email) | Q(username=username))

                if user:
                    if user.username == username:
                        context['error'] = "This username is taken."
                        return render(request, 'blog/register.html', context)
                    
                    context['error'] = "Email already exists."
                    return render(request, 'blog/register.html', context)
            except User.DoesNotExist:
                try:
                    validate_email(email)
                    validate_password(password)
  
                    user = User.objects.create(
                        email=email,
                        password=make_password(password), 
                        username=username,
                        first_name=name,
                        last_name=surname 
                    )
                    with_token = UserWithAuthToken.objects.create(user=user, token=uuid.uuid4())
                    with_token.save()
                    profile = Profile.objects.create(user_with_token=with_token)
                    profile.save()
                    user.save()
                    send_verificaton_email(
                        user.email, 
                        "Blog account actiavtion.",
                        f"Yo! Click this: http://127.0.0.1:8000/{with_token.token}"
                    )
                    context['success'] = "Success! Confirm your email now."
                    return render(request, "blog/register.html", context)
                
                except ValidationError as e:
                    context['error'] = str(e)
                    return render(request, 'blog/register.html', context)
                
            context['error'] = 'Something went wrong. Try again. Sorry!'
            return render(request, 'blog/register.html', context)
        else:
            errors = make_error_message(form.errors.as_data())
            context['error'] = errors
            return render(request, 'blog/register.html', context)            
    return render(request, "blog/register.html", context)


def activate_account(request, token):
    context = {
        'form': LoginForm(),
        'error': '', 
        'success': '',
        'user': request.user
    }
    try:
        user = UserWithAuthToken.objects.get(token=token)
        if token == user.token:
            user.activated = True
            user.save()
            context['success'] = "Activated! You can sign in now."
            return render(request, "blog/login.html", context)
    except User.DoesNotExist:
        context['form'] = RegistrationForm()
        context['error'] = "User doesn't exist."
        return render(request, 'blog/register.html', context)


def change_password(request):
    context = {
        'form': ChangePasswordForm(),
        'error': '',
        'success': '',
        'user': request.user
    }
    user = request.user
    if not user.is_authenticated:
        context['error'] = 'You need to be signed in to change your password.'
        context['form'] = LoginForm()
        return render(request, 'blog/login.html', context)
    if request.method == "POST":
        form = ChangePasswordForm(request.POST)

        if form.is_valid():
            old_password = form.cleaned_data['old_password']
            new_password = form.cleaned_data['new_password']

            try:
                validate_password(new_password)
                if check_password(old_password, user.password):
                    user.password = make_password(new_password)
                    user.save()
                    context['success'] = 'Password changed.'
                    return render(request, 'blog/change_password.html', context)
                else:
                    context['error'] = 'Wrong password.'
                    return render(request, 'blog/change_password.html', context)
            except ValidationError:
                context['error'] = 'Validation error, make sure your password isn\' to weak.'
                return render(request, 'blog/change_password.html', context)
        else:
            err = make_error_message(form.errors.as_data())
            context['error'] = err
            return render(request, 'blog/change_password.html', context)
    return render(request, 'blog/change_password.html', context)


def user_reset_password(request):
    context = {
        'form': ResetPasswordForm(),
        'error': '',
        'success': '',
        'user': request.user
    }
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                user = User.objects.get(email=email)
                with_token = UserWithAuthToken.objects.get(user=user)
                reset_token = uuid.uuid4()
                salt = bcrypt.gensalt()
                reset_tokens[str(reset_token)] = {
                    'email': user.email,
                    'salt': salt
                }
                hashed_token = bcrypt.hashpw(reset_token.bytes, salt)
                with_token.reset_token = hashed_token.decode('utf-8')
                with_token.reset_token_created_at = timezone.now()
                with_token.save()
                send_verificaton_email(
                    user.email,
                    "Blog - password reset",
                    f"Here's reset link, it will be valid for an hour. http://127.0.0.1:8000/reset_password/{reset_token}",    
                )
                context['success'] = 'Follow instructions sent to your email.'
                return render(request, "blog/reset_password.html", context)
            except User.DoesNotExist:
                context['error'] = "User doesn't exist."
                return render(request, 'blog/reset_password.html', context)
        else:
            errors = make_error_message(form.errors.as_data())
            context['error'] = errors
            return render(request, 'blog/reset_password.html', context)
    return render(request, 'blog/reset_password.html', context)

def reset_password(request, token):
    context = {
        'form': NewPasswordForm(),
        'error': '',
        'success': '',
        'user': request.user
    }
    if request.method == 'POST':
        form = NewPasswordForm(request.POST)

        if form.is_valid():
            new_password = form.cleaned_data["password"]
            try:
                data = reset_tokens.get(str(token))

                if data is None:
                    context['error'] = 'Wrong token. Reset password again.'
                    context['form'] = ResetPasswordForm()
                    return render(request, "blog/reset_password.html", context)
                
                user = User.objects.get(email=data.get('email'))
                user_with_token = UserWithAuthToken.objects.get(user=user)
                
                if timezone.now() - user_with_token.reset_token_created_at >= timedelta(hours=1):
                    context['error'] = 'Token is too old. Reset password again.'
                    context['form'] = ResetPasswordForm()
                    return render(request, "blog/reset_password.html", context)
                
                hashed_from_db = user_with_token.reset_token.encode('utf-8')
                hashed_token = bcrypt.hashpw(token.bytes, data.get('salt'))
                
                if hashed_token == hashed_from_db:
                    validate_password(new_password)
                    user.password = make_password(new_password)
                    user.save()
                    reset_tokens.pop(str(token))
                    context['success'] = 'Password changed, you can sign in now.'
                    context['token'] = token
                    return HttpResponseRedirect('login')

            except ValidationError as e:
                context['error'] = 'Password is too weak. (8 chars, not only numbers, can\'t be too common or similar to your data)'
                context['token'] = token
                return render(request, "blog/new_password.html", context)
            except User.DoesNotExist as e:
                context['error'] = str(e)
                context['form'] = ResetPasswordForm()
                return render(request, "blog/reset_password.html", context)
            except:
                context['error'] = "Something went wrong. Try again."
                context['form'] = ResetPasswordForm()
                return render(request, "blog/reset_password.html", context)
            
        else:
            errors = make_error_message(form.errors.as_data())
            context['error'] = errors
            return render(request, 'blog/new_password.html', context)    

    context['token'] = token
    return render(request, 'blog/new_password.html', context)
    
def user_login(request):
    context = {
        'form': LoginForm(),
        'error': '',
        'success': '',
        'user': request.user
    }


    if request.method == 'POST':
        form = LoginForm(request, request.POST)

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            try:
                user = User.objects.get(username=username)
                if user:
                    user_with_token = UserWithAuthToken.objects.get(user=user)
                    
                    if user_with_token and user_with_token.activated == False:
                        context['error'] = 'Activate your account.'
                        return render(request, 'blog/login.html', context)

                    user = authenticate(request, username=username, password=password)

                    if user:
                        login(request, user)
                        return HttpResponseRedirect('/')
                    else:
                        context['error'] = "Invalid credentials."
                        return render(request, 'blog/login.html', context)
            except (User.DoesNotExist, PermissionDenied):
                context['error'] = "User doesn't exist."
                return render(request, 'blog/login.html', context)
            context['error'] = "Something went wrong. Try again."
            return render(request, 'blog/login.html', context)
        else:
            errors = make_error_message(form.errors.as_data())
            context['error'] = errors
            return render(request, 'blog/login.html', context)
    else:
        return render(request, 'blog/login.html', context)
    
#END OF AUTH STUFF
#  
#PROFILE

def user_profile(request: HttpRequest, nickname):
    request_user: User = request.user
    is_following = False
    user = get_object_or_404(User, username=nickname)

    try:
        if request_user.id and request_user.username != user.username:
            req_profile: Profile = request_user.userwithauthtoken.profile
            req_profile.following.get(username=nickname)
            is_following = True

    except: pass

    if user:
        return render(request, "blog/user_profile.html", { 'user': user, 'req_user': request_user, 'is_following': is_following })



def edit_profile(request):
    user: User = request.user
    if not user.id: 
        return HttpResponse("Sign in to customize your profile.")
    profile: Profile = user.userwithauthtoken.profile
    context = {
        'form': ProfileEditForm(),
        'error': '',
        'success': '',
        'user': request.user
    }
    if request.method == "POST":
        form = ProfileEditForm(request.POST, request.FILES)

        if form.is_valid():
            avatar = request.FILES.get('avatar')
            about_me = form.cleaned_data['about_me']

            if avatar:
                if profile.avatar and profile.avatar != 'photos/default/user.png':
                    profile.avatar.delete()

                profile.avatar.save(f"{user.username}.jpg", avatar, save=False)
            if about_me:
                profile.about_me = about_me
            profile.save()
            return HttpResponseRedirect(reverse('profile', args=[user.username]))
        else:
            errors = make_error_message(form.errors.as_data())
            context['error'] = errors
            return render(request, 'blog/edit_profile.html', context)
    return render(request, 'blog/edit_profile.html', context)

def follow(request, nickname, unfollow):
    if request.method == "POST" and request.user.is_authenticated:
        current_user = request.user
        to_follow = get_object_or_404(User, username=nickname)

        current_user_profile = current_user.userwithauthtoken.profile
        to_follow_profile = to_follow.userwithauthtoken.profile

        if unfollow:
            if to_follow in current_user_profile.following.all():
                current_user_profile.following.remove(to_follow)
                to_follow_profile.followers.remove(current_user)

        elif current_user != to_follow:
            current_user_profile.following.add(to_follow)
            to_follow_profile.followers.add(current_user)

        return HttpResponseRedirect(reverse('profile', args=[nickname]))
    return HttpResponse("404")

#ENTRY
def add_entry(request):
    user = request.user
    if not user.id:
        return HttpResponseRedirect(reverse('login'))

    context = {
        'form': AddEntryForm(),
        'error': '',
        'success': '',
        'user': user
    }

    profile: Profile = user.userwithauthtoken.profile
    
    if request.method == "POST":
        form = AddEntryForm(request.POST, request.FILES)

        if form.is_valid():
            thumbnail = request.FILES.get('thumbnail', False)
            new_entry = form.save(False)
            new_entry.author = profile
            new_entry.save()

            if thumbnail:
                if new_entry.thumbnail and new_entry.thumbnail != "photos/default/blogentry.jpg":
                    new_entry.thumbnail.delete()
                new_entry.thumbnail.save(f"{new_entry.id}.jpg", thumbnail, save=True)

            context['success'] = 'Your entry have been posted.'
            return HttpResponseRedirect(reverse('entry_detail', args=[new_entry.id]))
        else:
            errors = make_error_message(form.errors.as_data())
            context['error'] = errors
            return render(request, 'blog/add_entry.html', context)
    return render(request, 'blog/add_entry.html', context)

def edit_entry(request, entry_id):
    entry = get_object_or_404(BlogEntry, id=entry_id)
    
    if entry.author.user_with_token.user.username != request.user.username:
        return HttpResponse('You can\'t edit this entry.')
    
    if request.method == "POST":
        new_thumbnail = request.FILES.get('thumbnail', False)
        new_title = request.POST.get('title')
        new_content = request.POST.get('content')

        if new_thumbnail:
            if entry.thumbnail and entry.thumbnail != 'photos/default/blogentry.jpg':
                entry.thumbnail.delete()
            entry.thumbnail.save(f"{entry.id}.jpg", new_thumbnail, save=False)

        if new_title:
            entry.title = new_title
        
        if new_content:
            entry.content = new_content

        entry.save()
        return HttpResponseRedirect(reverse('entry_detail', args=[entry.id]))
    else:
        form = EntryEditForm(instance=entry)
        return render(request, 'blog/entry_manage.html', {'form': form, 'entry_id': entry_id})

    
def remove_entry(request, entry_id):
    entry = get_object_or_404(BlogEntry, id=entry_id)
    
    if entry.author.user_with_token.user.username != request.user.username:
        return HttpResponse('You can\'t remove this entry.')
    
    entry.delete()
    return HttpResponseRedirect(reverse('profile'))

def entry_detail(request, entry_id):
    entry = get_object_or_404(BlogEntry, id=entry_id)
    return render(request, 'blog/entry.html', { 'entry': entry })