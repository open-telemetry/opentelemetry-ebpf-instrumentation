"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvoiceController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
let InvoiceController = class InvoiceController {
    getCatalog(account) {
        return this.invoices.catalog(account);
    }
    start(account, dto) {
        return this.invoices.start(account, dto);
    }
    getInvoice(account, id) {
        return this.invoices.byId(account, id);
    }
    createReceipt(account, id) {
        return this.invoices.receipt(account, id);
    }
};
exports.InvoiceController = InvoiceController;
__decorate([
    (0, common_1.Get)('catalog'),
    __param(0, (0, account_decorator_1.Account)())
], InvoiceController.prototype, "getCatalog", null);
__decorate([
    (0, common_1.Post)('start'),
    __param(0, (0, account_decorator_1.Account)()),
    __param(1, (0, common_1.Body)())
], InvoiceController.prototype, "start", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, account_decorator_1.Account)()),
    __param(1, (0, common_1.Param)('id'))
], InvoiceController.prototype, "getInvoice", null);
__decorate([
    (0, common_1.Post)(':id/receipt'),
    (0, common_1.HttpCode)(200),
    __param(0, (0, account_decorator_1.Account)()),
    __param(1, (0, common_1.Param)('id'))
], InvoiceController.prototype, "createReceipt", null);
exports.InvoiceController = InvoiceController = __decorate([
    (0, swagger_1.ApiTags)('Invoice'),
    (0, common_1.Controller)('invoice'),
    (0, common_1.UsePipes)(new common_1.ValidationPipe({ transform: true, whitelist: true }))
], InvoiceController);
