import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiExcludeEndpoint } from '@nestjs/swagger';
import { IsPublic } from './shared/decorators/auth.decorators';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) { }

  @IsPublic()
  @Get()
  @ApiExcludeEndpoint(true)
  getHello(): string {
    return this.appService.getPage();
  }
}
