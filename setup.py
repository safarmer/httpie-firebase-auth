from setuptools import setup, find_packages

setup(
    name='httpie-firebase-auth',
    version='0.3.1',
    packages=find_packages(),
    url='https://github.com/safarmer/httpie-firebase-auth',
    license='MIT',
    author='Shane Farmer',
    author_email='shane@secondbest.info',
    description='',
    py_modules=['firebase_auth'],
    zip_safe=False,
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_firebase_auth = firebase_auth:FirebaseAuthPlugin'
        ]
    },
    install_requires=[
        'requests>=2.26.0',
        'firebase-admin>=5.0.1',
        'httpie>=2.5.0',
        'gcloud>=0.18.3',
        'python_jwt>=3.3.0',
        'oauth2client>=4.1.3',
        'sseclient>=0.0.26',
        'PyCryptodome>=3.10.1',
        'PyJWT>=2.1.0',
        'requests_toolbelt>=0.9.1',
        'setuptools>=56.0.0',
    ],
)
