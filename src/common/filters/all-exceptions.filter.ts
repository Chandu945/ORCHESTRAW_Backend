import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { Prisma } from '@prisma/client';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    // In certain situations `httpAdapter` might not be available in the
    // constructor method, thus we should resolve it here.
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    // 1. Determine the Status Code & Error Type
    let httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let errorType = 'InternalServerError';

    // --- CASE A: NestJS Standard HTTP Exceptions ---
    if (exception instanceof HttpException) {
      httpStatus = exception.getStatus();
      const responseBody = exception.getResponse();

      // Handle class-validator array of errors vs single string
      if (typeof responseBody === 'object' && 'message' in responseBody) {
        message = (responseBody as any).message;
      } else {
        message = responseBody as string;
      }
      errorType = exception.name;
    }

    // --- CASE B: Prisma (Database) Exceptions ---
    else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      // P2002: Unique Constraint Violation (e.g. Email already exists)
      if (exception.code === 'P2002') {
        httpStatus = HttpStatus.CONFLICT;
        message = `Unique constraint failed on field: ${(exception.meta as any)?.target}`;
        errorType = 'Conflict';
      }
      // P2025: Record not found
      else if (exception.code === 'P2025') {
        httpStatus = HttpStatus.NOT_FOUND;
        message = 'Record not found';
        errorType = 'NotFound';
      }
      // Add other Prisma codes here as needed
    }

    // --- CASE C: Generic / Unexpected Errors ---
    else {
      // In production, never show the raw error message to the user for 500s
      // message = 'Internal Server Error';

      // For dev, we can see it:
      if (exception instanceof Error) {
        message = exception.message;
      }
    }

    // 2. Construct the JSON Response
    const responseBody = {
      statusCode: httpStatus,
      timestamp: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(ctx.getRequest()),
      method: httpAdapter.getRequestMethod(ctx.getRequest()),
      error: errorType,
      message: message,
    };

    // 3. Log the Error (Server Side)
    // We only log stack traces for 500 errors or unexpected crashes
    if (httpStatus >= 500) {
      this.logger.error(
        `Http Status: ${httpStatus} Error Message: ${JSON.stringify(message)}`,
        exception instanceof Error ? exception.stack : '',
      );
    } else {
      this.logger.warn(
        `Http Status: ${httpStatus} Error Message: ${JSON.stringify(message)}`,
      );
    }

    // 4. Send Response
    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
  }
}
