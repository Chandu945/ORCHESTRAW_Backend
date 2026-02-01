import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class OrchestrawFacebookGuard extends AuthGuard('orchestraw-facebook') {}
