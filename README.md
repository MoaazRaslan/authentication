installing requirement :
pip install requirements.txt

Endpoint:
1- POST : /register/
- body :
- {
- "username":"",
- "email":"",
- "password":"",
- "password2":"",
- "first_name":""
- }

2-POST : /login/

body :
{
"username":"",
"password":""
}

3-GET : verify-email/?token={token}


4-POST reset-password-request/
// send verification token to email
body :
{
"email":""
}

5-GET : reset-password-verification/?token={token}

//verify token

6-POST : reset-password/

//reset password
body : 
{
"token":"",
"password":"",
"password2":""
}

7-GET : account/users 

// for authenticated managers only 
// return list of users with their informations

8-PUT : account/user

//authenticated user
body :
{
"first_name":""
}
