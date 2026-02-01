import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class OrchestrawGoogleGuard extends AuthGuard('orchestraw-google') {}
