from django.contrib.sites.shortcuts import get_current_site
from typing import Any, Dict
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView, DeleteView, FormView
from django.urls import reverse_lazy
from django import forms

from django.contrib.auth.views import LoginView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login
from django.contrib.auth import get_user_model

from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from user.token import account_activation_token, password_reset_token
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from .models import Task

class LoginForm(AuthenticationForm):
    username = forms.CharField(label='Email / Username', widget=forms.TextInput(attrs={"autofocus": True}))

class RegisterForm(UserCreationForm):
    email = forms.EmailField(max_length=200, required=True)
    
    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'password1', 'password2',)

class CustomLoginView(LoginView):
    template_name = 'base/login.html'
    fields = '__all__'
    redirect_authenticated_user = True
    form_class = LoginForm

    def get_success_url(self) -> str:
        return reverse_lazy('tasks')

class RegisterPage(FormView):
    template_name = 'base/register.html'
    form_class = RegisterForm
    redirect_authenticated_user = True
    success_url = reverse_lazy('tasks')
    
    def form_valid(self, form):
        user = form.save(commit=False)
        user.is_active = False
        user.save()
        current_site = get_current_site(self.request)
        mail_subject = 'Activate your Todo List account.'
        message = render_to_string('base/acc_active_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        })
        to_email = form.cleaned_data.get('email')
        send_mail(
            mail_subject,
            message,
            "ranguo1108@gmail.com",
            [to_email],
            fail_silently=False,
        )
        return HttpResponse(f'An email was just sent to {to_email}, please check you email inbox to activate your account')
    
    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect('tasks')
        return super(RegisterPage, self).get(*args, **kwargs) 

def activate(request, uidb64, token):
    UserModel = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = UserModel.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        # login(request, user)
        # return redirect('home')
        return render(request, 'base/confirmation_success.html')
    else:
        return HttpResponse('Activation link is invalid!')

class ResetPasswordForm(forms.Form):
    email = forms.EmailField(max_length=200, required=True)

class ResetPasswordView(FormView):
    template_name = 'base/reset_password.html'
    form_class = ResetPasswordForm
    redirect_authenticated_user = True
    
    def form_valid(self, form: forms.Form) -> HttpResponse:
        UserModel = get_user_model()
        print(form.cleaned_data.get('email'))
        try:
            user = UserModel.objects.get(email=form.cleaned_data.get('email'))
        except UserModel.DoesNotExist:
            to_email = form.cleaned_data.get('email')
            return HttpResponse(f'An email with the password reset link was just sent to {to_email} if there is an account associated with that email address, please check you email inbox to reset your password')
        current_site = get_current_site(self.request)
        mail_subject = 'Reset the password of your Todo List account.'
        message = render_to_string('base/reset_password_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': password_reset_token.make_token(user),
        })
        to_email = form.cleaned_data.get('email')
        send_mail(
            mail_subject,
            message,
            "ranguo1108@gmail.com",
            [to_email],
            fail_silently=False,
        )
        
        return HttpResponse(f'An email with the password reset link was just sent to {to_email} if there is an account associated with that email address, please check you email inbox to reset your password')
    
class ActualResetPasswordForm(UserCreationForm):
    
    class Meta:
        model = get_user_model()
        fields = ('password1', 'password2',)

class ActualResetPasswordView(FormView):
    template_name = 'base/actual_reset_password.html'
    form_class = ActualResetPasswordForm
    redirect_authenticated_user = True
    
    def get(self, request: HttpRequest, *args: str, **kwargs: Any) -> HttpResponse:
        UserModel = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(kwargs['uidb64']))
            user = UserModel.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None
        if user is not None and password_reset_token.check_token(user, kwargs['token']):
            return super(ActualResetPasswordView, self).get(request, *args, **kwargs)
        else:
            return HttpResponse('Activation link is invalid!')
    
    def form_valid(self, form: forms.Form) -> HttpResponse:
        UserModel = get_user_model()
        user_tmp = form.save(commit=False)
        uid = force_str(urlsafe_base64_decode(self.kwargs['uidb64']))
        user = UserModel.objects.get(pk=uid)
        user.password = user_tmp.password
        user.save()
        return render(self.request, 'base/reset-password-success.html')

class TaskList(LoginRequiredMixin, ListView):
    model = Task
    context_object_name = 'tasks'

    def get_context_data(self, **kwargs: Any) -> Dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context['tasks'] = context['tasks'].filter(user=self.request.user)
        context['count'] = context['tasks'].filter(complete=False)
        
        search_input = self.request.GET.get('search-area') or ''
        if search_input:
            context['tasks'] = context['tasks'].filter(title__startswith=search_input)
        return context
    
class TaskDetail(LoginRequiredMixin, DetailView):
    model = Task
    context_object_name = 'task'
    template_name = 'base/task.html'
    
class TaskCreate(LoginRequiredMixin, CreateView):
    model = Task
    fields = ['title', 'description', 'complete']
    success_url = reverse_lazy('tasks')
    
    def form_valid(self, form):
        form.instance.user = self.request.user
        return super(TaskCreate, self).form_valid(form)

class TaskUpdate(LoginRequiredMixin, UpdateView):
    model = Task
    fields = ['title', 'description', 'complete']
    success_url = reverse_lazy('tasks')

class TaskDelete(LoginRequiredMixin, DeleteView):
    model = Task
    context_object_name = 'task'
    success_url = reverse_lazy('tasks')