/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
//import { decode } from 'jsonwebtoken'
import {verify, JWTPayload} from 'jsonwebtoken' //import jwt verify 
import * as security from '../lib/insecurity'

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const users = await UserModel.findAll()
    const secret = process.env.JWT_SECRET || ''
    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          try{
            const parsedToken = verify(userToken, secret) as JwtPayload
            if(parsedToken && parsedToken.iat){
              lastLoginTime = Math.floor(new Date(parsedToken.iat * 1000).getTime())
            }
          }catch (error){
            console.error('Error verifying token:', error)
          }
          //const parsedToken = decode(userToken, { json: true })
          //lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null
        }

        return {
          ...user.dataValues,
          password: user.password?.replace(/./g, '*'),
          totpSecret: user.totpSecret?.replace(/./g, '*'),
          lastLoginTime
        }
      })
    })
  } catch (error) {
    next(error)
  }
}

export default () => retrieveUserList
