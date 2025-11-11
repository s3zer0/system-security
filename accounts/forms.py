from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django import forms

class SignUpForm(UserCreationForm):
    # '이름' 필드
    first_name = forms.CharField(
        max_length=30, required=True, label="이름",
        widget=forms.TextInput(attrs={'placeholder': '홍길동', 'class': 'form-control'})
    )
    
    # '이메일' 필드
    email = forms.EmailField(
        max_length=254, required=True, label="이메일",
        widget=forms.EmailInput(attrs={'placeholder': 'you@domain.com', 'class': 'form-control'})
    )

    # '약관에 동의합니다' 체크박스
    agree_terms = forms.BooleanField(
        label="약관에 동의합니다",
        required=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username','first_name', 'email') 

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # '비밀번호' 필드
        self.fields['password1'].label = "비밀번호"
        self.fields['password1'].widget.attrs.update({
            'placeholder': '최소 8자',
            'class': 'form-control'
        })
        
        # '비밀번호 확인' 필드
        self.fields['password2'].label = "비밀번호 확인"
        self.fields['password2'].help_text = ''
        self.fields['password2'].widget.attrs.update({
            'placeholder': '비밀번호 다시 입력',
            'class': 'form-control'
        })

        self.fields['username'].widget = forms.HiddenInput()
        self.fields['username'].required = False

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            if User.objects.filter(username=email).exists():
                raise forms.ValidationError("이미 가입된 이메일입니다.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)

        user.username = self.cleaned_data['email'] # 이메일을 username으로 사용
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        if commit:
            user.save()
        return user