"""Initial schema for the MobInspect RBAC app."""
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ('codename', models.SlugField(max_length=100, unique=True)),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('category', models.CharField(db_index=True, max_length=50)),
                ('scope', models.CharField(
                    choices=[('action', 'Action'), ('resource', 'Resource')],
                    default='action', max_length=20,
                )),
                ('is_dangerous', models.BooleanField(default=False)),
            ],
            options={'ordering': ['category', 'codename']},
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=80, unique=True)),
                ('description', models.TextField(blank=True)),
                ('color', models.CharField(default='#64748B', max_length=7)),
                ('icon', models.CharField(default='shield', max_length=40)),
                ('is_system', models.BooleanField(
                    default=False,
                    help_text=(
                        'System roles cannot be deleted or renamed. '
                        'Their permission sets are still editable.'
                    ),
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('group', models.OneToOneField(
                    on_delete=models.deletion.CASCADE,
                    related_name='mi_role',
                    to='auth.group',
                )),
                ('permissions', models.ManyToManyField(
                    blank=True, related_name='roles', to='rbac.permission',
                )),
            ],
            options={'ordering': ['-is_system', 'name']},
        ),
        migrations.CreateModel(
            name='RoleAssignment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ('granted_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('granted_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=models.deletion.SET_NULL,
                    related_name='+', to=settings.AUTH_USER_MODEL,
                )),
                ('role', models.ForeignKey(
                    on_delete=models.deletion.CASCADE,
                    related_name='assignments', to='rbac.role',
                )),
                ('user', models.ForeignKey(
                    on_delete=models.deletion.CASCADE,
                    related_name='role_assignments',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-granted_at'],
                'unique_together': {('user', 'role')},
            },
        ),
        migrations.CreateModel(
            name='AuditEvent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ('action', models.CharField(db_index=True, max_length=80)),
                ('target_type', models.CharField(blank=True, max_length=50)),
                ('target_id', models.CharField(blank=True, max_length=80)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.CharField(blank=True, max_length=400)),
                ('occurred_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('actor', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=models.deletion.SET_NULL,
                    related_name='+', to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['-occurred_at']},
        ),
        migrations.CreateModel(
            name='ApiKey',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=80)),
                ('prefix', models.CharField(db_index=True, max_length=12)),
                ('key_hash', models.CharField(max_length=64, unique=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(
                    on_delete=models.deletion.CASCADE,
                    related_name='api_keys',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['-created_at']},
        ),
    ]
