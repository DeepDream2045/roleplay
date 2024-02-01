# Generated by Django 5.0.1 on 2024-02-01 15:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("roleplay_manager", "0008_rename_review_feedback_content_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="characterinfo",
            name="image",
            field=models.ImageField(blank=True, null=True, upload_to="character/"),
        ),
        migrations.AlterField(
            model_name="customuser",
            name="profile_image",
            field=models.ImageField(
                blank=True, default="", null=True, upload_to="profile/"
            ),
        ),
    ]
