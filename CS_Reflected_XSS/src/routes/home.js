/**
 * Home / Landing Page Route Handler
 */

const express = require('express');
const router = express.Router();
const { renderLayout } = require('../views/layout');
const { renderHomePage } = require('../views/pages');

router.get('/', (req, res) => {
  const bodyContent = renderHomePage();
  const html = renderLayout({
    title: 'Lab Overview',
    activeMode: 'home',
    bodyContent
  });
  res.status(200).send(html);
});

module.exports = router;
