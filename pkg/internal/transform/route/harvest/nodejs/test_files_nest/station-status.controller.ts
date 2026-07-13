// Example NestJS controller without a route prefix
import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';

@Controller()
export class StationStatusController {
  @Public()
  @Get('/uptime')
  @HttpCode(HttpStatus.OK)
  public getUptime() {
    return this.monitor.check(this.probes);
  }

  @Get('/ping')
  public getPing() {
    return 'PONG';
  }
}
