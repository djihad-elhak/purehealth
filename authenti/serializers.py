from rest_framework import serializers
from .models import Client,Wilaya,City



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = '__all__'

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = ['email', 'phone', 'password']



class WilayaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wilaya
        fields = ['id', 'name']

class CitySerializer(serializers.ModelSerializer):
    class Meta:
        model = City
        fields = ['id', 'name','wilaya']


class PersonalInfoSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Client
        fields = ['name', 'last_name', 'birth_date', 'wilaya', 'city']
        
class IdCardSerializer(serializers.Serializer):
    file = serializers.FileField()

class UploadFileSerializer(serializers.Serializer):
    file = serializers.FileField()


class OTPSerializer(serializers.Serializer):
        

            otp = serializers.CharField(max_length=6)





class ChangePassword(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data



class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = Client
        fields = ['id_number', 'email', 'password','phone','name','last_name','birthdate','wilaya','city']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = self.Meta.model(**validated_data)
        if password is not None:
            user.set_password(password)
        user.save()
        return user

