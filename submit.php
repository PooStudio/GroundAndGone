<?php
// Secure contact form handler for Ground & Gone

// Start session for CSRF protection
session_start();

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Function to sanitize input
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Function to validate email
function is_valid_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Function to validate phone (basic)
function is_valid_phone($phone) {
    $phone = preg_replace('/\D/', '', $phone);
    return strlen($phone) >= 10 && strlen($phone) <= 15;
}

// Function to validate image file
function is_valid_image($file) {
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $max_size = 5 * 1024 * 1024; // 5MB

    if (!in_array($file['type'], $allowed_types)) {
        return false;
    }
    if ($file['size'] > $max_size) {
        return false;
    }
    return true;
}

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // CSRF check
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed.");
    }

    // Honeypot check
    if (!empty($_POST['website'])) {
        die("Spam detected.");
    }

    // Sanitize and validate inputs
    $name = sanitize_input($_POST['name']);
    $phone = sanitize_input($_POST['phone']);
    $email = sanitize_input($_POST['email']);
    $message = sanitize_input($_POST['message']);

    $errors = [];

    if (empty($name)) {
        $errors[] = "Name is required.";
    }

    if (empty($phone) || !is_valid_phone($phone)) {
        $errors[] = "Valid phone number is required.";
    }

    if (empty($email) || !is_valid_email($email)) {
        $errors[] = "Valid email is required.";
    }

    if (empty($message)) {
        $errors[] = "Message is required.";
    }

    // Check file upload
    if (!isset($_FILES['photo']) || $_FILES['photo']['error'] !== UPLOAD_ERR_OK) {
        $errors[] = "Photo upload is required.";
    } elseif (!is_valid_image($_FILES['photo'])) {
        $errors[] = "Invalid photo file. Only JPEG, PNG, GIF, WebP under 5MB allowed.";
    }

    if (empty($errors)) {
        // Process the form

        // Move uploaded file
        $upload_dir = 'uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        $file_name = uniqid() . '_' . basename($_FILES['photo']['name']);
        $file_path = $upload_dir . $file_name;

        if (move_uploaded_file($_FILES['photo']['tmp_name'], $file_path)) {
            // Send email
            $to = "groundandgone@gmail.com";
            $subject = "New Contact Form Submission from Ground & Gone";
            $body = "Name: $name\nPhone: $phone\nEmail: $email\nMessage: $message\nPhoto: Attached";

            $headers = "From: $email\r\n";
            $headers .= "Reply-To: $email\r\n";
            $headers .= "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: multipart/mixed; boundary=\"boundary\"\r\n";

            // Email body with attachment
            $email_body = "--boundary\r\n";
            $email_body .= "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
            $email_body .= $body . "\r\n\r\n";
            $email_body .= "--boundary\r\n";
            $email_body .= "Content-Type: " . $_FILES['photo']['type'] . "; name=\"$file_name\"\r\n";
            $email_body .= "Content-Disposition: attachment; filename=\"$file_name\"\r\n";
            $email_body .= "Content-Transfer-Encoding: base64\r\n\r\n";
            $email_body .= chunk_split(base64_encode(file_get_contents($file_path))) . "\r\n";
            $email_body .= "--boundary--";

            if (mail($to, $subject, $email_body, $headers)) {
                // Success
                header("Location: contact.html?status=success");
                exit();
            } else {
                $errors[] = "Failed to send email.";
            }
        } else {
            $errors[] = "Failed to upload photo.";
        }
    }

    // If errors, display them
    if (!empty($errors)) {
        echo "<h2>Errors:</h2><ul>";
        foreach ($errors as $error) {
            echo "<li>$error</li>";
        }
        echo "</ul>";
        echo "<p><a href='contact.html'>Go back</a></p>";
        exit();
    }
} else {
    // Not a POST request
    header("Location: contact.html");
    exit();
}
?>
