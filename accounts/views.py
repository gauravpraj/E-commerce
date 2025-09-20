from django.shortcuts import render,redirect
from django.http import HttpResponse
from .forms import RegistrationForm
from .models import Account
from django.contrib import messages , auth
from django.contrib.auth.decorators import login_required

# varification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode , urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from carts.models import Cart,CartItem
from carts.views import _cart_id

# Create your views here.
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_number = form.cleaned_data['phone_number']
            password = form.cleaned_data['password']
            confirm_password = form.cleaned_data['confirm_password']
            
            username = first_name+' '+last_name
            
            user = Account.objects.create_user(first_name=first_name , last_name=last_name , email=email , password=password, username=username)
            user.phone_number = phone_number
            user.save()
            
            # USER ACTIVATION
            current_site = get_current_site(request)
            email_subject = "Please activate your account"
            message = render_to_string('accounts/account_verification_email.html',{
                'user' : user,
                'domain' : current_site.domain,
                'uid' : urlsafe_base64_encode(force_bytes(user.id)),
                'token' : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(email_subject , message , to=[to_email])
            send_email.send()
            
            # messages.success(request, "Registration successful")
            return redirect('/accounts/login?command=verification&email='+email)
    else:
        form = RegistrationForm()
    context = {
        'forms' : form,
    }
    return render(request , "accounts/register.html" , context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        
        user = auth.authenticate(email = email , password=password)
        if user is not None:
            cart = Cart.objects.get(cart_id=_cart_id(request))
            cart_item_exists = CartItem.objects.filter(cart=cart).exists()
            if cart_item_exists:
                cart_item = CartItem.objects.filter(cart=cart)
                
                # Gettting the product variation by cart_id
                product_variation = []
                for item in cart_item:
                    variation = item.variations.all()
                    product_variation.append(list(variation))
                    
                # Get the cart item from the user to access his product variation
                cart_item = CartItem.objects.filter(user=user)
                ex_var_list = []
                id = []
                for item in cart_item:
                    existing_variation = item.variations.all()
                    ex_var_list.append(list(existing_variation))
                    id.append(item.id)
                    
                for pr in product_variation:
                    if pr in ex_var_list:
                        index = ex_var_list.index(pr)
                        item_id = id[index]
                        item = CartItem.objects.get(id=item_id)
                        item.quantity += 1
                        item.user = user
                        item.save()
                    else:
                        cart_item = CartItem.objects.filter(cart=cart)
                        for item in cart_item:
                            item.user = user
                            item.save()
                
            auth.login(request,user)
            messages.success(request , "Login successful")
            return redirect('dashboard')
        else:
            messages.error(request , "invalid login credential")
            return redirect('login')
    return render(request , 'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request, "You are logged out!")
    return redirect('login')

def activate(request , uidb64 , token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError , ValueError, OverflowError , Account.DoesNotExist):
        user = None
        
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request , 'Congratulation ! Your account is activated')
        return redirect('login')
    
    else:
        messages.error(request , 'Invalid activation link')
        return redirect('register')
    

def dashboard(request):
    return render(request , 'accounts/dashboard.html')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact = email)
            
            # Reset Password
            current_site = get_current_site(request)
            email_subject = "Reset Password"
            message = render_to_string('accounts/reset_password.html',{
                'user' : user,
                'domain' : current_site.domain,
                'uid' : urlsafe_base64_encode(force_bytes(user.id)),
                'token' : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(email_subject , message , to=[to_email])
            send_email.send()
            
            messages.success(request , "Password reset email is sent to your email address")
            return redirect('login')
        else:
            messages.error(request , 'Account does not exist!')
            return redirect('forgotPassword')
    return render(request , 'accounts/forgotPassword.html')

def reset_password_validate(request , uidb64 , token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError , ValueError, OverflowError , Account.DoesNotExist):
        user = None
        
    if user is not None and default_token_generator.check_token(user , token):
        request.session['uid'] = uid
        messages.success(request , "please reset your password")
        return redirect('resetPassword')
    else:
        messages.error(request, "This link has been expired")
        return redirect('login')
    
def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            uid = request.session.get('uid')        
            user = Account.objects.get(id=uid)
            user.set_password(password)
            user.save()
            messages.success(request , "password reset successful")
            return redirect('login')
        else:
            messages.error(request , "Password not match")
            return redirect('resetPassword')
    return render(request, 'accounts/resetPassword.html')
