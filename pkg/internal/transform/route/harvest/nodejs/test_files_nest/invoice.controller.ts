// Example NestJS controller with a route prefix and class-validator DTOs
import { Body, Controller, Get, HttpCode, Param, Post, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { StartInvoiceDto } from './dto/start-invoice.dto';

@ApiTags('Invoice')
@Controller('invoice')
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class InvoiceController {
  @Get('catalog')
  getCatalog(@Account() account?: AccountDto) {
    return this.invoices.catalog(account);
  }

  @Post('start')
  start(@Account() account, @Body() dto: StartInvoiceDto) {
    return this.invoices.start(account, dto);
  }

  @Get(':id')
  getInvoice(@Account() account, @Param('id') id: string) {
    return this.invoices.byId(account, id);
  }

  @Post(':id/receipt')
  @HttpCode(200)
  createReceipt(@Account() account, @Param('id') id: string) {
    return this.invoices.receipt(account, id);
  }
}
