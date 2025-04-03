/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import axios from 'axios'
import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

/*
1. Function: imagevalidator()
2. validate URL
3. validate Protocol
4. validate extension
*/
const allowedHosts = ['juiceshop.com', 'example.com']
function isImageValidator(urlString:string): boolean{
  try{
    const url = new URL(urlString)

    //allwed protocols
    if(!['http:', 'https:'].includes(url.protocol)){
      return false
    }

    //restricted whitelisted Hosts
    if(!allowedHosts.includes(url.hostname)) return false

    //file extension validation
    const validExt = ['.jpg', '.jpeg', '.png', '.svg', '.gif'] 
    const ext = url.pathname.slice(url.pathname.lastIndexOf('.'))
    if(!validExt.includes(ext)) return false

    return true
  }
  catch{
    return false
  }
}

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      //validate Image
      if(!isImageValidator(url)){
        return res.status(400).json({error: 'Invalid Image URL'})
      }
      //if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        /*const imageRequest = request
          .get(url)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
          })*/

        try {
          
          const response = await axios.get(url, {
            responseType: 'stream',
            timeout: 5000, // 5 seconds timeout
            maxContentLength: 1024 * 1024 * 5, 
            headers: {
              'User-Agent': 'JuiceShop ImageUploader',
            },
          });
          if (response.status === 200) {
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(
              url.split('.').slice(-1)[0].toLowerCase()
            )
              ? url.split('.').slice(-1)[0].toLowerCase()
              : 'jpg';

            const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`;
            const writeStream = fs.createWriteStream(filePath);

            response.data.pipe(writeStream);

            writeStream.on('finish', async () => {
              await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
                return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` });
              });
              res.location(process.env.BASE_PATH + '/profile');
              res.redirect(process.env.BASE_PATH + '/profile');
            });

            writeStream.on('error', (err) => {
              logger.error(`Error saving image: ${utils.getErrorMessage(err)}`);
              next(err);
            });

        }
       else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
  
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
