from django.contrib import admin

# Register your models here.
from .models import Client,Wilaya,City,Client
admin.site.register(Client)
admin.site.register(Wilaya)
admin.site.register(City)

