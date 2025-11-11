from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django import forms
from django.contrib.auth import password_validation # ⬅️ 1. 이 줄을 추가합니다.

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

    #비밀번호 검사관련 코드
    def clean(self):
        cleaned_data = super(UserCreationForm, self).clean()

        password = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password and password2 and password != password2:
            self.add_error('password2', forms.ValidationError("두 비밀번호가 일치하지 않습니다."))
        
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except forms.ValidationError as error:
                korean_errors = []
                for e in error.error_list:
                    if e.code == 'password_too_short':
                        korean_errors.append(forms.ValidationError(
                            f"비밀번호는 최소 {e.params.get('min_length', 8)}자 이상이어야 합니다.",
                            code=e.code
                        ))
                    elif e.code == 'password_common':
                        korean_errors.append(forms.ValidationError(
                            "비밀번호가 너무 일상적입니다.",
                            code=e.code
                        ))
                    elif e.code == 'password_entirely_numeric':
                        korean_errors.append(forms.ValidationError(
                            "비밀번호는 숫자로만 구성될 수 없습니다.",
                            code=e.code
                        ))
                    else:
                        korean_errors.append(e)
                    
                self.add_error('password1', korean_errors)

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)

        user.username = self.cleaned_data['email'] # 이메일을 username으로 사용
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        if commit:
            user.save()
        return user