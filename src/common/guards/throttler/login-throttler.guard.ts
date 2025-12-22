// import { Injectable } from '@nestjs/common';
// import { ThrottlerGuard } from '@nestjs/throttler';

// @Injectable()
// export class LoginThrottlerGuard extends ThrottlerGuard {
//   protected async getTracker(req: Record<string, any>): Promise<string> {
//     // Track by IP address
//     return req.ips?.length ? req.ips[0] : req.ip;
//   }

//   protected errorMessage = 'Too many login attempts. Please try again later.';
// }
