from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model 

class CustomUserCreationForm(UserCreationForm):
    agree_to_terms = forms.BooleanField(
        label='약관에 동의합니다',
        required=True,
        widget=forms.CheckboxInput(),
        error_messages={
            'required': '약관에 동의하셔야 가입이 가능합니다.'
        }
    )

    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        
        fields = ('username', 'email', 'password')