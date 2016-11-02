=====
django-onering
=====

OneRing cryptographic identity for Django.

Quick start
-----------

1. Add "django-onering" to INSTALLED_APPS:
  INSTALLED_APPS = {
    ...
    'django-onering'
  }

2. Run `python manage.py syncdb` to create OneRing's models.

4. Run the development server and access http://127.0.0.1:8000/admin/ to
    manage OneRing objects.
