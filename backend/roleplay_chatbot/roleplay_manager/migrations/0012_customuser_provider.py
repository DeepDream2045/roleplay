# Generated by Django 5.0.1 on 2024-02-05 12:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("roleplay_manager", "0011_alter_customuser_username_alter_feedback_types"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="provider",
            field=models.CharField(
                blank=True, default="magic link", max_length=60, null=True
            ),
        ),
    ]
