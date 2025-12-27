const express = require('express');
const app = express();

app.use(express.json());

app.post('/api/paypal/webhook', (req, res) => {
  console.log('PayPal webhook received');
  console.log(req.body);
  res.sendStatus(200);
});

app.get('/', (req, res) => {
  res.send('API is running');
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
