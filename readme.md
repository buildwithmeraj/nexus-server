# Nexus - Club Management Platform

A comprehensive Node.js/Express backend server for managing clubs, events, memberships, and payments. Built with MongoDB, Firebase Authentication, and Stripe integration.

## 🌐 Live Demo

- **Server**: [https://nexus-server-flame-theta.vercel.app/](https://nexus-server-flame-theta.vercel.app/)
- **Client**: [https://nexus-2ev.pages.dev/](https://nexus-2ev.pages.dev/)
- **Client Repository**: [buildwithmeraj/nexus](https://github.com/buildwithmeraj/nexus)

## ✨ Features

### Core Functionality

- **Club Management**: Create, update, and manage clubs with approval workflow
- **Event Management**: Schedule and manage club events with registration tracking
- **Membership System**: Handle club memberships with auto-expiration
- **Payment Processing**: Stripe integration for memberships and event registrations
- **User Roles**: Support for members, club managers, and admins

### User Types

- **Members**: Join clubs, register for events, view statistics and payment history
- **Club Managers**: Create and manage clubs, host events, view club analytics
- **Admins**: System administration, user role management, platform statistics

### Analytics & Statistics

- Payment statistics and revenue tracking
- Member growth and engagement metrics
- Event attendance analytics
- Club performance dashboards
- Monthly spending breakdown

## 🛠️ Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js v5.2.1
- **Database**: MongoDB with Atlas
- **Authentication**: Firebase Admin SDK
- **Payment Processing**: Stripe
- **CORS**: Enabled for cross-origin requests
- **Environment**: dotenv for configuration

## 📦 Dependencies

```json
{
  "cors": "^2.8.5",
  "dotenv": "^17.2.3",
  "express": "^5.2.1",
  "firebase-admin": "^13.6.0",
  "mongodb": "^7.0.0",
  "stripe": "^20.0.0"
}
```

## 🚀 Getting Started

### Prerequisites

- Node.js v14+
- MongoDB Atlas account
- Stripe account
- Firebase project

### Installation

1. Clone the repository

```bash
git clone <repository-url>
cd nexus-server
```

2. Install dependencies

```bash
npm install
```

3. Configure environment variables

```bash
cp .env.example .env
```

4. Set up .env with your credentials:

```
MONGODB_URI=your_mongodb_connection_string
STRIPE_SECRET_KEY=your_stripe_secret_key
CLIENT_URL=your_client_url
PORT=3000
FB_SERVICE_KEY=your_firebase_base64_encoded_key
```

5. Start the server

```bash
npm start
```

## 📚 API Routes

### Public Routes

- `GET /` - Server health check
- `GET /clubs` - List all clubs with filters
- `GET /clubs/categories` - Get club categories
- `GET /clubs/details/:id` - Get club details
- `GET /events` - List all events with filters
- `GET /events/:eventId` - Get event details
- `GET /users/role/:email` - Get user role
- `POST /users` - Create new user

### Member Routes (Protected)

- `GET /member/statistics` - User statistics
- `GET /member/clubs` - User's clubs
- `GET /member/events` - User's registered events
- `GET /member/memberships` - User's memberships
- `GET /member/payments` - User's payment history
- `GET /member/activity-summary` - Activity dashboard
- `GET /member/spending-by-type` - Spending breakdown
- `GET /member/payment-timeline` - 12-month payment history
- `POST /clubs/:clubId/join` - Join a club
- `POST /clubs/:clubId/confirm-payment` - Confirm membership payment
- `POST /events/:eventId/register` - Register for event
- `POST /clubs/:clubId/renew-membership` - Renew membership
- `DELETE /memberships/:membershipId` - Cancel membership
- `DELETE /event-registrations/:registrationId` - Cancel event registration

### Club Manager Routes (Protected)

- `GET /clubs/:param` - Get manager's clubs
- `POST /clubs` - Create new club
- `PATCH /clubs/:id` - Update club
- `DELETE /clubs/:id` - Delete club
- `POST /clubs/:clubId/events` - Create event
- `PATCH /events/:eventId` - Update event
- `DELETE /events/:eventId` - Delete event
- `GET /club-manager/statistics` - Manager statistics
- `GET /manager/payments` - Manager's payments
- `GET /manager/payments/statistics` - Payment statistics

### Admin Routes (Protected)

- `GET /admin/stats` - Platform statistics
- `GET /admin/clubs` - All clubs
- `GET /admin/users` - All users
- `GET /admin/payments` - All payments
- `GET /admin/club-manager-applications` - Pending applications
- `PATCH /clubs/status/:id` - Update club status
- `PATCH /users/role/:id` - Update user role
- `PATCH /admin/club-manager-applications` - Approve applications

## 🔐 Authentication

The server uses Firebase Authentication with JWT tokens. Include the token in the Authorization header:

```
Authorization: Bearer <firebase_token>
```

## 💳 Payment Integration

Stripe is integrated for:

- Club membership payments
- Event registration payments
- Automatic payment recording and history

## 🗄️ Database Schema

### Collections

- **usersCollection** - User accounts and roles
- **clubsCollection** - Club information
- **membershipsCollection** - User club memberships
- **eventsCollection** - Club events
- **eventRegistrationsCollection** - Event registrations
- **paymentsCollection** - Payment records
- **applicationsCollection** - Club manager applications

## 📊 Deployment

Deployed on **Vercel** using the Vercel Node runtime.

### Deployment Configuration

- **Build**: index.js
- **Runtime**: `@vercel/node`
- **Routes**: All requests directed to index.js

## 🔐 Security

- Firebase Authentication for user verification
- Role-based access control (RBAC)
- Environment variables for sensitive data
- CORS configured for specific origins
- Secure payment processing with Stripe

## 📝 Notes

- Firebase service key is base64 encoded in environment variables
- MongoDB indexes are automatically created on startup
- Expired memberships are auto-marked when checked
- All monetary values stored in USD
- Timestamps use ISO 8601 format

## 📄 License

MIT

## 👤 Author

Meraj Islam - [GitHub](https://github.com/buildwithmeraj)

---

For issues or contributions, please visit the [client repository](https://github.com/buildwithmeraj/nexus).
