# Generated by Django 4.2.4 on 2023-08-31 13:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0003_rename_actiaved_userwithauthtoken_activated_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profile',
            old_name='user',
            new_name='user_with_token',
        ),
    ]
