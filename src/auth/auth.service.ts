import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signin() {
    return {
      msg: 'Signed in',
    };
  }

  signup() {
    return {
      msg: 'Signedup',
    };
  }
}
