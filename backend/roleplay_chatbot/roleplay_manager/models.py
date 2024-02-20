from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from shortuuidfield import ShortUUIDField
import random
import json


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

    def create_guest_user(self):
        guest_username = f"guest_{random.randint(1000000, 9999999)}"
        guest_email = f"{guest_username}@mail.com"

        guest_user = self.model(
            username=guest_username,
            email=guest_email,
            password="Download@1",  # You can choose to set a default password for guest users
            is_active=True,
            is_guest=True,
        )

        guest_user.save(using=self._db)
        return guest_user


class CustomUser(AbstractBaseUser, BaseModel, PermissionsMixin):
    """Using email instead of username."""

    id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=60, null=True, blank=True)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=100, null=True, blank=True)
    phone = models.CharField(max_length=15, null=True, blank=True)
    profile_image = models.ImageField(
        upload_to='profile/', default='', null=True, blank=True)
    email_confirmation = models.BooleanField(default=False)
    stay_sign = models.BooleanField(default=False, null=True, blank=True)
    provider = models.CharField(
        max_length=60, default='magic link', null=True, blank=True)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_guest = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = CustomUserManager()    

    def __str__(self):
        """Str method to return User Email name."""
        return '{}'.format(self.email)

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        try:
            # self.clean()
            if not self.full_name:
                self.full_name = f"{self.email.split('@')[0]}"
            if not self.username:
                self.username = f"{self.email.split('@')[0]}{random.randint(0000000, 9999999)}"
        except Exception as e:
            print(e)
        super(CustomUser, self).save()


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


class Tag(TimeStampedModel):
    id = models.AutoField(primary_key=True)
    tag_name = models.CharField(max_length=50)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='tag')

    def __str__(self):
        return self.tag_name


class ModelInfo(TimeStampedModel):
    model_name = models.CharField(max_length=255)
    short_bio = models.TextField(null=False, blank=False)
    model_location = models.CharField(max_length=255)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='model_infos')
    is_public = models.BooleanField(default=True)

    def __str__(self):
        return self.model_name


class UserCustomModel(TimeStampedModel):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='custom_user_modal')
    custom_model_info = models.ForeignKey(
        ModelInfo, on_delete=models.CASCADE, related_name='custom_model_info')
    is_default = models.BooleanField(default=True)
    prompt_template = models.TextField(default="")
    temperature = models.FloatField(default=0.85, validators=[
                                    MinValueValidator(0), MaxValueValidator(2)])
    repetition_penalty = models.FloatField(
        default=1.15, validators=[MinValueValidator(0.01), MaxValueValidator(2)])
    top_p = models.FloatField(default=0.8, validators=[
                              MinValueValidator(0.01), MaxValueValidator(0.99)])
    top_k = models.IntegerField(default=50, validators=[
                                MinValueValidator(-1), MaxValueValidator(100)])

    def __str__(self):
        return f"{self.id}"


class CharacterInfo(models.Model):

    VISIBILITY_CHOICES = [
        ('private', 'Private'),
        ('unlisted', 'Unlisted'),
        ('public', 'Public'),
    ]

    id = models.AutoField(primary_key=True)
    character_name = models.CharField(max_length=100)
    short_bio = models.TextField(null=False, blank=False)
    character_gender = models.CharField(max_length=10, null=False, blank=False)
    # tags = models.CharField(max_length=100, null=False, blank=False)
    tags = models.ManyToManyField(
        "roleplay_manager.Tag", related_name='character_tag')
    model_id = models.ForeignKey(
        ModelInfo, on_delete=models.CASCADE, related_name='character_model')
    prompt = models.TextField(null=False, blank=False)
    character_story = models.TextField(null=False, blank=False)
    character_visibility = models.CharField(
        max_length=10, choices=VISIBILITY_CHOICES, default='unlisted',)
    initial_message = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='character/', null=True, blank=True)
    NSFW = models.BooleanField(default=False)
    lorebook = models.TextField(null=True, blank=True)
    language = models.CharField(
        max_length=50, default="ENGLISH", null=True, blank=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='character_infos')
    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.character_name


class Lorebook(TimeStampedModel):
    name = models.CharField(max_length=200)
    description = models.TextField(null=True, blank=True)
    is_public = models.BooleanField(default=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='lorebook_infos')


class LorebookEntries(TimeStampedModel):
    name = models.CharField(max_length=200)
    keys = models.TextField(null=True, blank=True)
    condition = models.CharField(max_length=20)
    secondary_keys = models.TextField(null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    probability = models.IntegerField(default=100)
    order = models.IntegerField(default=100)
    is_enabled = models.BooleanField(default=True)
    is_exclude_recursion = models.BooleanField(default=False)
    lorebook = models.ForeignKey(
        Lorebook, on_delete=models.CASCADE, related_name='lorebook_entry_infos')

    @property
    def convert_keys_list(self):
        self.keys = json.loads(str(self.keys))
        return self.keys

    @property
    def convert_secondary_keys_list(self):
        self.keys = json.loads(str(self.keys))
        self.secondary_keys = json.loads(str(self.secondary_keys))
        return self.secondary_keys


class ChatRoom(TimeStampedModel):
    DM_ROOM = 1
    GROUP_ROOM = 2

    ROOM_TYPE = (
        (DM_ROOM, 'DM'),
        (GROUP_ROOM, 'Group')
    )
    room_id = ShortUUIDField()
    type = models.PositiveIntegerField(choices=ROOM_TYPE, default=DM_ROOM)
    group_name = models.CharField(max_length=30, null=True, blank=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='sender')
    character = models.ForeignKey(
        CharacterInfo, on_delete=models.CASCADE, related_name='character')
    # member = models.ManyToManyField('users.CustomUser', related_name='room_members')
    # is_active = models.BooleanField(default=False)

    def __str__(self):
        return self.room_id + ' - ' + str(self.group_name)

    @property
    def get_group_name(self):
        if self.group_name is None:
            if self.type == 'Group':
                return self.user.full_name + ' - ' + self.character.character_name
            return self.character.character_name
        return self.group_name


class ChatMessage(TimeStampedModel):
    """creating chat message table for store chat data"""

    chat = models.ForeignKey(
        ChatRoom, on_delete=models.CASCADE, related_name='chatroom')
    user_message = models.TextField(null=True, blank=True)
    character_message = models.TextField(null=True, blank=True)
    is_edited = models.BooleanField(default=False)

    def __str__(self):
        return self.chat.user.email


class Feedback(TimeStampedModel):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='feedback')
    types = models.CharField(max_length=255)
    content = models.TextField()

    def __str__(self):
        return f"{self.user.full_name}"
