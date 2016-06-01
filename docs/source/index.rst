IAM Manager documentation!
=====================================

Introduction:
=============

Managing AWS resources among IAM users easily and securely.
	* AWS Identity and Access Management (IAM) Users
	* Simple Storage Service (S3)
	* Amazon Elastic Compute Cloud (EC2)
	* Amazon Simple Email Service (SES)


Installation procedure
======================

* Get code from git repository https://github.com/MicroPyramid/IAM-Manager
* use virtualenv to install requirements and you can run the site.

Login
======================
You can log in with provided UserName, AccessKey, SecretKey. As per the AWS Service, Root credentials are not shared and doesn't contain UserName. So, You need to create IAM User with all previliges as root user and then they can log in with those credentials.

	* After Sucessfully logged in, You will redirected to dashboard with provided Menu having different Amazon resources and logged in UserName.
	    1. EC2
	    2. S3
	    3. SNS
	    4. SES
	    5. CloudFront

You can easily navigate to previous pages by using Breadcrumbs.

Elastic Compute Cloud (EC2)
==============================
The action of click on EC2 Link directs you to list of all available instances in that region. 
You can filter required instances by choosing respective region. 
Even you can alter the status of Instance to START, STOP, TERMINATE by changing the actions.
	* START: Starts an Amazon EBS-backed AMI that you've stopped previously.
	* STOP: Stops an Amazon EBS-backed instance. Attached devices won't be deleted, when you  				stop an instance. 
	* TERMINATE: Shuts down the instance. Amazon EC2 deletes all EBS volumes that were attached 				when the instance launched. 
You can view detailed information of any instances available, by clicking on View Icon.


Simple Storage Service (S3)
=============================
Amazon S3 is to store and retrieve any amount of data at any time. You can give permission to specific Buckets.

The action of clicking on S3 link redirects to list of all buckets available. By clicking on Plus button at the right side of table, a form will appear to create new bucket (Bucket Name and region). By this you can add new Bucket in that region.

Click on trash icon, for deleting a bucket and then it'll pop out a confirmation message whether to delete or not and you should specify bucket name(Which one you want to delete). If you don't want to delete any bucket then you can close the popup. 


Simple Email Service (SES)
=============================
The action of click on SES Link directs you to list of all available identities in that region. 
You can filter required identities by choosing respective region.

By clicking on Plus button at the right side of table, a form will appear to create new Identity (Email). By this you can add new Identity in that region. 

Click on trash icon, for deleting an identity and then it'll pop out a confirmation message whether to delete or not and you should specify Identity(Which one you want to delete). If you don't want to delete any Identity then you can close the popup.

To get Identity details, click on the Arrow Icon in the table. Which provides the details of Email Feedback, Delivery Notifications SNS, Bounce Notifications, Complaint Notifications SNS of specific Identity. 

To Send Email(s) from specific identity, Click on Email Icon in the table. Which redirects to the Email form, by providing valid data by client, Sends an email message with header and content specified by the client.
You can only send email from verified email addresses otherwise, you will get an "Email address not verified" error.


Identity and Access Management IAM USERS
===============================================
The action of click on USERS Link directs you to list of all IAM Users.

By clicking on Plus button at the right side of table, a form will be appeared to create new IAM User with UserName(required), choosing password and generate keys(optional)
For creating password for IAM User you need to choose/select first checkbox, select second checkbox for generating a new access keys

Creates a new AWS secret access key and corresponding AWS access key ID for the specified user. The default status for new keys is Active.

Click on trash icon, for deleting an IAM User and then it'll pop out a confirmation message whether to delete or not and you should specify IAM User(Which one you want to delete). If you don't want to delete any IAM User then you can close the popup.

You can view detailed information of any IAM User, by clicking on View Icon.
Here you can change Password of the IAM User by clicking on "Change Password" link and also you can generate access key by clicking on "Generate Keys" link, if it's not generated while creating user. After clicking "Generate Keys" link a pop up window will be appeared with the generated access key and you should download that access key for further purpose.

And you can't be login to the system without your access key.

To Attach policy to the IAM User, click on attach policy will redirects to list of Attached policies.
You can easily Navigate to Default Policies, Attached policies and custom Policy by choosing required checkbox.
	1. Attached Policies: Displays all Attached policies to the specific IAM User.
	2. Default Policices: Displays all Default policies available in AWS
	3. Custom Policy: creating your own policy for the SES, S3 Buckets, EC2. 
