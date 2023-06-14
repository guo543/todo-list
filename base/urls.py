from django.urls import path, re_path
from .views import TaskList, TaskDetail, TaskCreate, TaskUpdate, TaskDelete, CustomLoginView, RegisterPage, activate, ResetPasswordView, ActualResetPasswordView
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('activate/<uidb64>/<token>/',
        activate, name='activate'),
    path('actual-reset-password/<uidb64>/<token>/',
        ActualResetPasswordView.as_view(), name='actual-reset-password'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('register/', RegisterPage.as_view(), name='register'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('reset-password', ResetPasswordView.as_view(), name='reset-password'),
    path('', TaskList.as_view(), name='tasks'),
    path('task/<int:pk>/', TaskDetail.as_view(), name='task'),
    path('task-create/', TaskCreate.as_view(), name='task-create'),
    path('task-update/<int:pk>/', TaskUpdate.as_view(), name='task-update'),
    path('task-delete/<int:pk>/', TaskDelete.as_view(), name='task-delete'),
]
