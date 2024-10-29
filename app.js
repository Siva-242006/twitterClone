const express = require('express')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const path = require('path')

const app = express()
app.use(express.json())
let db
const dbPath = path.join(__dirname, 'twitterClone.db')

const dbInitializer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })

    app.listen(3000, () => {
      console.log('Server is running...')
    })
  } catch (error) {
    console.log(`DB error: ${error.message}`)
  }
}

dbInitializer()

const authenticateToken = (request, response, next) => {
  let jwtToken
  const headers = request.headers['authorization']
  if (headers !== undefined) {
    jwtToken = headers.split(' ')[1]
  }
  if (headers === undefined) {
    response.status(401)
    response.send('Invalid JWT Token')
  } else {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        response.status(401)
        response.send('Invalid JWT Token')
      } else {
        request.user = payload
        next()
      }
    })
  }
}

app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body
  const query = `SELECT * FROM user WHERE username = "${username}";`
  const isUser = await db.get(query)
  if (isUser === undefined) {
    if (password.length < 6) {
      response.status(400)
      response.send('Password is too short')
    } else {
      const bcryptPassword = await bcrypt.hash(password, 10)
      const insertQuery = `INSERT INTO user(username, password, name, gender) VALUES("${username}", "${bcryptPassword}", "${name}", "${gender}");`
      const dbResponse = await db.run(insertQuery)
      response.status(200)
      response.send('User created successfully')
    }
  } else {
    response.status(400)
    response.send('User already exists')
  }
})

app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const query = `SELECT * FROM user WHERE username = "${username}";`
  const isUser = await db.get(query)
  if (isUser === undefined) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const isPasswordRight = await bcrypt.compare(password, isUser.password)
    if (isPasswordRight === true) {
      const payload = {username: username}
      const jwtToken = await jwt.sign(payload, 'MY_SECRET_TOKEN')
      response.send({jwtToken})
    } else {
      response.status(400)
      response.send('Invalid password')
    }
  }
})

app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const {username} = request.user
  const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
    username,
  ])

  const tweetsQuery = `
    SELECT 
      user.username,
      tweet.tweet,
      tweet.date_time AS dateTime
    FROM 
      follower 
      JOIN tweet ON follower.following_user_id = tweet.user_id 
      JOIN user ON tweet.user_id = user.user_id
    WHERE 
      follower.follower_user_id = ?
    ORDER BY 
      tweet.date_time DESC
    LIMIT 4
  `

  const tweets = await db.all(tweetsQuery, [user.user_id])
  response.send(tweets)
})

app.get('/user/following/', authenticateToken, async (request, response) => {
  const {username} = request.user
  const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
    username,
  ])

  const followerQuery = `
    SELECT 
      user.name
    FROM 
      follower 
      JOIN user ON follower.following_user_id = user.user_id
    WHERE 
      follower.follower_user_id = ?;
  `

  const following = await db.all(followerQuery, [user.user_id])
  response.send(following)
})

app.get('/user/followers/', authenticateToken, async (request, response) => {
  const {username} = request.user
  const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
    username,
  ])

  const followerQuery = `
    SELECT 
      user.name
    FROM 
      follower 
      JOIN user ON follower.follower_user_id = user.user_id
    WHERE 
      follower.following_user_id = ?;
  `

  const follower = await db.all(followerQuery, [user.user_id])
  response.send(follower)
})

app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const {tweetId} = request.params
  const {username} = request.user
  const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
    username,
  ])

  const userTweetQuery = `
    SELECT 
      tweet.tweet,
      tweet.date_time AS dateTime,
      (SELECT COUNT(*) FROM like WHERE tweet_id = tweet.tweet_id) AS likes,
      (SELECT COUNT(*) FROM reply WHERE tweet_id = tweet.tweet_id) AS replies
    FROM 
      tweet 
      JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE 
      tweet.tweet_id = ?
      AND follower.follower_user_id = ?
  `

  const tweetDetails = await db.get(userTweetQuery, [tweetId, user.user_id])

  if (tweetDetails) {
    response.send(tweetDetails)
  } else {
    response.status(401).send('Invalid Request')
  }
})

app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const {tweetId} = request.params
  const {username} = request.user
  const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
    username,
  ])

  const userTweetQuery = `
    SELECT 
      tweet.tweet,
      tweet.date_time AS dateTime,
      (SELECT COUNT(*) FROM like WHERE tweet_id = tweet.tweet_id) AS likes,
      (SELECT COUNT(*) FROM reply WHERE tweet_id = tweet.tweet_id) AS replies
    FROM 
      tweet 
      JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE 
      tweet.tweet_id = ?
      AND follower.follower_user_id = ?
  `

  const tweetDetails = await db.get(userTweetQuery, [tweetId, user.user_id])

  if (tweetDetails) {
    response.send(tweetDetails)
  } else {
    response.status(401).send('Invalid Request')
  }
})

app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {username} = request.user

    const userQuery = `SELECT user_id FROM user WHERE username = ?`
    const user = await db.get(userQuery, username)

    const followsQuery = `
    SELECT 1 
    FROM follower 
    JOIN tweet ON follower.following_user_id = tweet.user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?
  `
    const isFollowing = await db.get(followsQuery, [user.user_id, tweetId])

    if (!isFollowing) {
      response.status(401).send('Invalid Request')
    } else {
      const repliesQuery = `
      SELECT 
        user.name, 
        reply.reply 
      FROM 
        reply 
        JOIN user ON reply.user_id = user.user_id 
      WHERE 
        reply.tweet_id = ?
    `
      const replies = await db.all(repliesQuery, tweetId)
      response.send({replies})
    }
  },
)

app.get('/user/tweets/', authenticateToken, async (request, response) => {
  const {username} = request.user
  const query = `SELECT * FROM user WHERE username = "${username}";`
  const user = await db.get(query)
  const userTweetsQuery = `
    SELECT 
      tweet.tweet,
      COUNT(DISTINCT like.like_id) AS likes,
      COUNT(DISTINCT reply.reply_id) AS replies,
      tweet.date_time AS dateTime
    FROM 
      tweet
      LEFT JOIN like ON tweet.tweet_id = like.tweet_id
      LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
    WHERE 
      tweet.user_id = ?
    GROUP BY 
      tweet.tweet_id
  `

  const userTweets = await db.all(userTweetsQuery, [user.user_id])
  response.send(userTweets)
})

app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const {username} = request.user
  const {tweet} = request.body
  const query = `SELECT * FROM user WHERE username = "${username}";`
  const user = await db.get(query)
  const insertTweetQuery = `
    INSERT INTO tweet (tweet, user_id, date_time)
    VALUES (?, ?, ?)
  `

  const dateTime = new Date().toISOString().replace('T', ' ').replace('Z', '')
  await db.run(insertTweetQuery, [tweet, user.user_id, dateTime])
  response.send('Created a Tweet')
})

app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {username} = request.user

    const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
      username,
    ])

    const tweetQuery = `SELECT * FROM tweet WHERE tweet_id = ? AND user_id = ?`
    const tweet = await db.get(tweetQuery, [tweetId, user.user_id])

    if (!tweet) {
      response.status(401).send('Invalid Request')
    } else {
      const deleteTweetQuery = `DELETE FROM tweet WHERE tweet_id = ?`
      await db.run(deleteTweetQuery, tweetId)
      response.send('Tweet Removed')
    }
  },
)

app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {username} = request.user

    const userQuery = `SELECT user_id FROM user WHERE username = ?`
    const user = await db.get(userQuery, username)

    const followsQuery = `
    SELECT 1 
    FROM follower 
    JOIN tweet ON follower.following_user_id = tweet.user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?
  `
    const isFollowing = await db.get(followsQuery, [user.user_id, tweetId])

    if (!isFollowing) {
      response.status(401).send('Invalid Request')
    } else {
      const likesQuery = `
      SELECT 
        user.username
      FROM 
        like 
        JOIN user ON like.user_id = user.user_id 
      WHERE 
        like.tweet_id = ?
    `
      const likes = await db.all(likesQuery, tweetId)
      const usernames = likes.map(like => like.username)
      response.send({likes: usernames})
    }
  },
)

module.exports = app
