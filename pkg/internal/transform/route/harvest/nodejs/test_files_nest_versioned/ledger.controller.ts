// Example NestJS controller using the array form of @Controller()
import { Body, Controller, Get, Post } from '@nestjs/common';

@Controller(['ledger', 'books'])
export class LedgerController {
  @Get('summary')
  getSummary() {
    return this.ledger.summary();
  }

  @Post()
  append(@Body() entry: LedgerEntryDto) {
    return this.ledger.append(entry);
  }
}
