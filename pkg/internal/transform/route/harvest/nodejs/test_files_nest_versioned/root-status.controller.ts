// Example prefix-less NestJS controller with a bare method decorator: the
// real route is the global prefix + default version (/api/v1)
import { Controller, Get } from '@nestjs/common';

@Controller()
export class RootStatusController {
  @Get()
  getStatus() {
    return this.status.overview();
  }
}
