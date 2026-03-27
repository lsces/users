<?php
// test_email.php

$to = 'lester@lsces.uk'; // Replace with the recipient's email address
$subject = 'Test Email';
$message = 'This is a test email to verify email forwarding.';
$headers = 'From: root@rdm1.uk' . "\r\n" . // Replace with the sender's email address
'Reply-To: support@rdm1.uk' . "\r\n" . // Replace with the sender's email address
'X-Mailer: PHP/' . phpversion();

if (mail($to, $subject, $message, $headers)) {
	echo 'Email sent successfully to ' . $to;
} else {
	echo 'Failed to send email to ' . $to;
}
