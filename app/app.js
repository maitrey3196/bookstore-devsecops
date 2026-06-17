const express = require('express');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = "admin123";

const books = [
  { id: 1, title: "Docker Deep Dive", author: "Nigel Poulton", price: 30 },
  { id: 2, title: "Kubernetes Up & Running", author: "Kelsey Hightower", price: 40 },
  { id: 3, title: "OWASP Testing Guide", author: "OWASP", price: 20 },
  { id: 4, title: "DevSecOps Handbook", author: "Gene Kim", price: 50 }
];

const users = [];
const orders = [];

app.get('/', (req,res)=>{
  res.send('Online Book Store Running');
});

app.get('/books',(req,res)=>{
  res.json(books);
});

app.get('/search',(req,res)=>{
  const keyword = req.query.q || '';

  const result = books.filter(
    b => b.title.toLowerCase().includes(keyword.toLowerCase())
  );

  res.json(result);
});

app.post('/register',(req,res)=>{

  users.push({
    username:req.body.username,
    password:req.body.password
  });

  res.send("User Registered");
});

app.post('/login',(req,res)=>{

  const username=req.body.username;
  const password=req.body.password;

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if(user){
      res.send("Login Successful");
  } else {
      res.send("Invalid Credentials");
  }
});

app.post('/order',(req,res)=>{

  orders.push({
    username:req.body.username,
    book:req.body.book
  });

  res.send("Order Placed");
});

app.get('/orders',(req,res)=>{
  res.json(orders);
});

app.listen(3000,()=>{
  console.log("Book Store running on port 3000");
});
