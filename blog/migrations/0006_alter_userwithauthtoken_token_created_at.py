# Generated by Django 4.2.4 on 2023-08-31 15:30

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0005_userwithauthtoken_token_created_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userwithauthtoken',
            name='token_created_at',
            field=models.DateTimeField(default=datetime.datetime(2023, 8, 31, 15, 30, 33, 978363, tzinfo=datetime.timezone.utc)),
        ),
    ]
