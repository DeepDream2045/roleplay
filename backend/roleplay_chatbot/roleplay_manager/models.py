from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

class BaseModel(models.Model):
    """Base model for created and modified date."""

    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        """Meta class."""
        abstract = True

class CustomUserManager(BaseUserManager):
    """Well.. using BaseUserManager."""
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_active', True)
        return self._create_user(email, password,  **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, BaseModel, PermissionsMixin):
    """Using email instead of username."""

    id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=60, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=100, null=True, blank=True)
    phone = models.CharField(max_length=15, null=True, blank=True)
    profile_image = models.ImageField(upload_to='', default='', null=True, blank=True)
    email_confirmation = models.BooleanField(default=False)
    stay_sign = models.BooleanField(default=False, null=True, blank=True)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __str__(self):
        """Str method to return User Email name."""
        return '{}'.format(self.email)

class TokenRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expiration_time = models.DateTimeField()

    def __str__(self):
        return self.user.email

class TimeStampedModel(models.Model):
    """TimeStampedModel model for created and modified date."""

    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        """Meta class."""
        abstract = True

class ChatMessage(TimeStampedModel):
    """creating chat message table for store chat data"""

    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sender_user', null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    receiver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='receiver_user', null=True, blank=True)
    room_group_name = models.CharField(max_length=255, null=True, blank=True)
    group_id = models.CharField(max_length=255, null=True, blank=True)
    is_edited = models.BooleanField(default=False)

    def __str__(self):
        return self.sender.email

class Tag(TimeStampedModel):
    tag_id = models.AutoField(primary_key=True)
    tag_name = models.CharField(max_length=50)
    user_added_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='tag')

    def __str__(self):
        return self.tag_name

class CharacterInfo(models.Model):
    id = models.AutoField(primary_key=True)
    character_name = models.CharField(max_length=100)
    short_bio = models.TextField()
    character_gender = models.CharField(max_length=20)
    tag_id = models.ForeignKey(Tag, on_delete=models.CASCADE)  # Assuming there is a Tag model
    prompt = models.TextField()
    display_prompt = models.TextField()
    initial_message = models.TextField()
    image = models.ImageField(upload_to='character_images/')  # Assuming images are uploaded to 'character_images/' folder
    NSFW = models.BooleanField(default=False)
    lorebook = models.TextField()
    language = models.CharField(max_length=50, default="ENGLISH", null=True, blank=True)
    user_id = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='character_infos', null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.character_name

class ModelInfo(TimeStampedModel):
    user_id = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='model_infos', null=True, blank=True)
    model_name = models.CharField(max_length=255)
    model_location = models.CharField(max_length=255)
    used_for = models.CharField(max_length=255)
    accessibility = models.CharField(max_length=50)
    prompt_template = models.TextField()
    temperature = models.FloatField(default=0.85, validators=[MinValueValidator(0), MaxValueValidator(2)])
    repetition_penalty = models.FloatField(default=1.15, validators=[MinValueValidator(0.01), MaxValueValidator(2)])
    top_p = models.FloatField(default=0.8, validators=[MinValueValidator(0.01), MaxValueValidator(0.99)])
    top_k = models.IntegerField(default=50, validators=[MinValueValidator(-1), MaxValueValidator(100)])

    def __str__(self):
        return self.model_name

class Feedback(TimeStampedModel):
    user_id = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='feedback', null=True, blank=True)
    rating = models.IntegerField()
    review = models.TextField()