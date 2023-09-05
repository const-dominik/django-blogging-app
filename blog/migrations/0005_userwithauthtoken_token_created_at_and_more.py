# Generated by Django 4.2.4 on 2023-08-31 15:29

import datetime
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0004_rename_user_profile_user_with_token'),
    ]

    operations = [
        migrations.AddField(
            model_name='userwithauthtoken',
            name='token_created_at',
            field=models.DateTimeField(default=datetime.datetime(2023, 8, 31, 17, 29, 53, 250821)),
        ),
        migrations.AlterField(
            model_name='profile',
            name='user_with_token',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='blog.userwithauthtoken'),
        ),
    ]
