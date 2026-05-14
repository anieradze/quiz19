var express = require('express');
var router = express.Router();

const bcrypt = require('bcrypt');
const User = require('../models/User');
const authMiddleware = require('/authMiddleware');

router.get('/register', function(req, res) {
    res.render('register', { error: null });
});

router.post('/register', async function(req, res) {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.render('register', {
                error: 'All fields are required'
            });
        }
        if (password.length < 6) {
            return res.render('register', {
                error: 'Password must be at least 6 characters'
            });
        }
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.render('register', {
                error: 'Email already exists'
            });
        }

        const user = new User({
            email,
            password
        });
        await user.save();
        res.redirect('/auth/login');

    } catch (err) {
        console.log(err);
        res.render('register', {
            error: 'Something went wrong'
        });
    }
});

router.get('/login', function(req, res) {
    res.render('login', { error: null });
});

router.post('/login', async function(req, res) {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.render('login', {
                error: 'All fields are required'
            });
        }
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', {
                error: 'Invalid email or password'
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.render('login', {
                error: 'Invalid email or password'
            });
        }
        req.session.userId = user._id;
        res.redirect('/auth/dashboard');

    } catch (err) {
        console.log(err);

        res.render('login', {
            error: 'Something went wrong'
        });
    }
});
router.get('/dashboard', authMiddleware, async function(req, res) {

    const user = await User.findById(req.session.userId);

    res.render('dashboard', {
        user
    });
});

router.get('/profile', authMiddleware, async function(req, res) {

    const user = await User.findById(req.session.userId);

    res.render('profile', {
        user
    });
});

router.get('/change-password', authMiddleware, function(req, res) {
    res.render('change-password', {
        error: null,
        success: null
    });
});

router.post('/change-password', authMiddleware, async function(req, res) {

    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.session.userId);
        const isMatch = await bcrypt.compare(
            currentPassword,
            user.password
        );

        if (!isMatch) {
            return res.render('change-password', {
                error: 'Current password is incorrect',
                success: null
            });
        }

        if (newPassword.length < 6) {
            return res.render('change-password', {
                error: 'New password must be at least 6 characters',
                success: null
            });
        }
        user.password = newPassword;
        await user.save();
        res.render('change-password', {
            error: null,
            success: 'Password updated successfully'
        });
    } catch (err) {
        console.log(err);
        res.render('change-password', {
            error: 'Something went wrong',
            success: null
        });
    }
});

router.get('/logout', function(req, res) {
    req.session.destroy(function() {
        res.redirect('/auth/login');
    });
});

module.exports = router;