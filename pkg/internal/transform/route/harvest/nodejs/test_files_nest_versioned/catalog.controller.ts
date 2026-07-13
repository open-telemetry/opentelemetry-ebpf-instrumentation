// Example NestJS controller using the object form of @Controller() with a version
import { Controller, Get, Param, Version } from '@nestjs/common';

@Controller({ path: 'catalog', version: '2' })
export class CatalogController {
  @Get('featured')
  getFeatured() {
    return this.catalog.featured();
  }

  @Get(':sku')
  getItem(@Param('sku') sku: string) {
    return this.catalog.bySku(sku);
  }

  @Version('3')
  @Get('preview')
  getPreview() {
    return this.catalog.preview();
  }

  // decorator order within a stack is arbitrary: @Version() below @Get()
  @Get('history')
  @Version('4')
  getHistory() {
    return this.catalog.history();
  }

  @Get('archive')
  getArchive() {
    return this.catalog.archive();
  }
}
