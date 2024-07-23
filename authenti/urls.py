from django.urls import path
from . import views
from django.urls import path,include
from .views import RegisterStep1View, VerifyOTPView, RegisterStep3View, RegisterStep4View





urlpatterns = [
        path('upload/', views.upload_file, name='upload_file'),
         path('register/step1/', RegisterStep1View.as_view(), name='register_step1'),
    path('register/verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('register/step3/', RegisterStep3View.as_view(), name='register_step3'),
        path('register/step4/', RegisterStep4View.as_view(), name='register_step4'),


]